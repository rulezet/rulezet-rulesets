rule Lazarus_Torisma_config {
    meta:
        description = "Torisma config header"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "b78efeac54fa410e9e3e57e4f3d5ecc1b47fd4f7bf0d7266b3cb64cefa48f0ec"

     strings:
        $header = { 98 11 1A 45 90 78 BA F9 4E D6 8F EE }

     condition:
        all of them
}