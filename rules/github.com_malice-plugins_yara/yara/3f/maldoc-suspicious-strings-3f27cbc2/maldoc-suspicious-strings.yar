rule maldoc_suspicious_strings
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a01 = "CloseHandle"
        $a02 = "CreateFile"
        $a03 = "GetProcAddr"
        $a04 = "GetSystemDirectory"
        $a05 = "GetTempPath"
        $a06 = "GetWindowsDirectory"
        $a07 = "IsBadReadPtr"
        $a08 = "IsBadWritePtr"
        $a09 = "LoadLibrary"
        $a10 = "ReadFile"
        $a11 = "SetFilePointer"
        $a12 = "ShellExecute"
        $a13 = "UrlDownloadToFile"
        $a14 = "VirtualAlloc"
        $a15 = "WinExec"
        $a16 = "WriteFile"
    condition:
        any of them
}