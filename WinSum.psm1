# WinSum.psm1
# Written by David Winton (https://github.com/dwin10)
# Version: 0.1
# Provided under the MIT License

<#
 .Synopsis
  Generates checksums for files and directories
 .Description
  Generates checksum file hashes for a variety of algorithms for the purposes of file validation.
 .Parameter Mode
  Sets the mode of operation.
 .Parameter Path
  The path to a given file or directory.
 .Parameter Algorithm
  Sets the hashing algorithm to be used in the checksum operation (Default: SHA256).
 .Parameter Hash
  Specific previously known hash, which can be used in Compare mode.
 .Parameter OutFile
  Boolean value that when set will generate a checksum file in the same directory as -Path.
 .Example
   # Checksum a single file, and output to console.
   WinSum -Mode File -Path C:\Test\TestDoc-1.txt
 .Example
   # Checksum an entire directory using the MD5 algorithm and create a checksum file.
   WinSum -Mode Directory -Path C:\Test\ -Algorithm MD5 -OutFile
 .Example
   # Perform a check operation on a checksum file.
   WinSum -Mode Check -Path C:\Test\MD5SUMS.txt -Algorithm MD5
 .Example
   # Perform a compare operation on a file with a known hash
   WinSum -Mode Compare -Path C:\Test\TestDoc-1.txt -Algorithm MD5 -Hash 4765C0B343E5431B301BC375628B4DED
#>

function WinSum {
    [cmdletbinding()]

    param (
    [Parameter(ParameterSetName="SelectMode", Mandatory=$true)][ValidateSet("File", "Directory", "Check", "Compare")][string]$Mode,
    [Parameter(ParameterSetName="SelectMode", Mandatory=$true)][string]$Path,
    [ValidateSet("MD5", "SHA1", "SHA256", "SHA384", "SHA512")][string]$Algorithm,
    [string]$Hash,
    [switch]$OutFile
    )

    function Get-FileChecksum([string]$InFile) {
        $FileResults = Get-FileHash -Algorithm $Algorithm $InFile
        return $FileResults.Hash + "  " + $FileResults.Path
    }

    function Get-FileExists([string]$fn) {
        return Test-Path -Path $fn -PathType Leaf
    }

    # Set the Hashing Algorithm, SHA256 as default
    if ( -not $Algorithm ) {
        $Algorithm = "SHA256"
    }

    # If OutFile is to be generated, then set the outfile name to match the algorithm
    if ( $OutFile ) {
        $OutFileName = $Algorithm + "SUMS.txt"
    }

    if ($Mode -eq "Check") {
        Write-Verbose "Checksum File: $Path"

        $ChecksumFileContent = Get-Content $Path
    
        foreach ($Checksum in $ChecksumFileContent) {
            $SplitChecksum = $Checksum.Split("", 2)
            $StoredChecksum = $SplitChecksum[0].Trim().ToUpper()
            $PathToFile = $SplitChecksum[1].Trim()

            # If the file can't be found then try searching in the same directory as the checksum file
            if ( -not (Get-FileExists($PathToFile)) ) {
                $CheckSumFileDirectoryPath = (Get-Item $Path).Directory.FullName
                $PathToFile = [System.IO.Path]::Combine($CheckSumFileDirectoryPath, $PathToFile)
            }

            # try block will fail if file can't be found
            try {
                $FileChecksum = (Get-FileHash -Algorithm $Algorithm $PathToFile -ErrorAction stop).Hash 

                if ( $StoredChecksum.Equals($FileChecksum) ) {
                    Write-Host -ForegroundColor Green "[ PASS ]" $PathToFile
                }
                else {
                    Write-Host -ForegroundColor Red "[ FAIL ]" $PathToFile
                    Write-Verbose "Expected: $StoredChecksum"
                    Write-Verbose "Returned: $FileChecksum"
                }
            }
            catch {
                Write-Host -ForegroundColor Red "[-] File does not exist at this path:" $PathToFile  
            }
        } 
        Write-Host -ForegroundColor Green "[+] Operation Complete!" 
    }

    elseif ($Mode -eq "Compare") {
        $Hash = $Hash.Trim().ToUpper()
        Write-Verbose "Path: $Path"
        Write-Verbose "Hash: $Hash"

        if ( $Hash -and $Path ) { 
            if (Get-FileExists($Path)) { 
                $FileHash = (Get-FileHash -Algorithm $Algorithm $Path).Hash
                if ($Hash.Equals($FileHash)) { 
                    Write-Host -ForegroundColor Green "[ PASS ]" $Path
                }
                else {
                    Write-Host -ForegroundColor Red "[ FAIL ]" $Path
                    Write-Verbose "Expected: $Hash"
                    Write-Verbose "Returned: $FileHash"
                }
                Write-Host -ForegroundColor Green "[+] Operation Complete!" 
            }
            else {
                Write-Host -ForegroundColor Red "[-] File does not exist at this path:" $Path
            }
        }
        else {
            Write-Host -ForegroundColor Red "[-] To use Compare mode, both the -Hash and -Path flags must be set correctly"
        }
    }

    elseif ($Mode -eq "Directory") {
        Write-Verbose "Mode: Directory" 
        Write-Verbose "Path: $Path"
        Write-Verbose "Algorithm: $Algorithm"
        Write-Verbose "Generate checksums file: $OutFile"
    
        if (Test-Path -Path $Path -PathType Container) {
            # Check if $OutFile is set or not, if set but not provided then set path to same directory as $Path
            # If SHA256SUMS.txt already exists, remove it
            if ($OutFile) {
                $OutFilePath = [IO.Path]::Combine($Path, $OutFileName)
                if ( Get-FileExists($OutFilePath) ) { 
                    Remove-Item $OutFilePath
                }
            }

            $Files = @(Get-ChildItem $Path)
            foreach ($f in $Files) {
                $FilePath = [IO.Path]::Combine($Path,$f)
                if (Get-FileExists($FilePath)) {
                    $FileChecksum = Get-FileChecksum($FilePath)
                    if ($OutFile) {
                        Add-Content $OutFilePath $FileChecksum
                        $FileChecksum
                    }
                    else {
                        $FileChecksum
                    }
                }
                else {
                    Write-Host -ForegroundColor Red "[-]" $FilePath "is not a file and will not be processed, continuing checksum operation.."
                    continue
                }
            }
            Write-Host -ForegroundColor Green "[+] Operation Complete!" 
        }
        else {
            Write-Host -ForegroundColor Red "[-] Directory mode was selected, but path is not a valid directory!"
        }

    }

    elseif ($Mode -eq "File") {
        Write-Verbose "Mode: File"
        Write-Verbose "Path: $Path"
        Write-Verbose "Algorithm: $Algorithm"
        Write-Verbose "Generate checksums file: $OutFile"

        if ( Get-FileExists($Path) ) {
            $FileChecksum = Get-FileChecksum($Path)
            if ($OutFile) {
                $DirPath = (Get-Item $Path).Directory.FullName
                $OutFilePath = [IO.Path]::Combine($DirPath, $OutFileName)
                if ( Get-FileExists($OutFilePath) ) { 
                    Remove-Item $OutFilePath
                }
                Add-Content $OutFilePath $FileChecksum
                $FileChecksum
            }
            else {
                $FileChecksum
            }
            Write-Host -ForegroundColor Green "[+] Operation Complete!" 
        }
        else {
            Write-Host -ForegroundColor Red "[-] File mode was selected, but path is not a valid file!"
        }
    }
}

Export-ModuleMember -Function WinSum
