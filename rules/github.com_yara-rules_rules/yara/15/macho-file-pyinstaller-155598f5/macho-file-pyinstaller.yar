rule MachO_File_pyinstaller
{
    meta:
        author = "KatsuragiCSL (https://katsuragicsl.github.io)"
        description = "Detect Mach-O file produced by pyinstaller"
    strings:
        $a = "pyi-runtime-tmpdir"
        $b = "pyi-bootloader-ignore-signals"
    condition:
        any of them
}