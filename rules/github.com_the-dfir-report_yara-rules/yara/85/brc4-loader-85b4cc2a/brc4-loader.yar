rule BRC4_Loader {
    meta:
        description = "Detects BRC4 Loader"
        author = "The DFIR Report, RussianPanda"
		id = "aae537a8-ba8f-4d92-94f2-554dd0cad8cd"
		reference = "https://thedfirreport.com/2025/09/29/from-a-single-click-how-lunar-spider-enabled-a-near-two-month-intrusion"
        date = "2025-06-24"
        hash1 = "6c3b2490e99cd8397fb79d84a5638c1a0c4edb516a4b0047aa70b5811483db8f"
		hash2 = "f4cb6b684ea097f867d406a978b3422bbf2ecfea39236bf3ab99340996b825de"
    strings:
        $s1 = {44 0F BE 4D AF 33 C9 [0-5] 41 C1 E1 03 41 B8}
        $s2 = {0F B6 C9 48 8D 52 01 83 C9 60 03 C1 0F B6 0A 03 C0 84 C9 75 EB}
    condition:
        uint16(0) == 0x5A4D and all of them and filesize < 5MB
}