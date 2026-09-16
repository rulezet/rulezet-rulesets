rule REDLEAVES_DroppedFile_ImplantLoader_Starburn {
    meta:
        description = "Detects the DLL responsible for loading and deobfuscating the DAT file containing shellcode and core REDLEAVES RAT"
        author = "USG"
        reference = "https://www.us-cert.gov/ncas/alerts/TA17-117A"
        true_positive = "7f8a867a8302fe58039a6db254d335ae"         id = "976f42b1-58c9-554b-97e6-130a657507e2"
    strings:
        $XOR_Loop = {32 0c 3a 83 c2 02 88 0e 83 fa 08 [4-14] 32 0c 3a 83 c2 02 88 0e 83 fa 10}     condition:
        any of them
}