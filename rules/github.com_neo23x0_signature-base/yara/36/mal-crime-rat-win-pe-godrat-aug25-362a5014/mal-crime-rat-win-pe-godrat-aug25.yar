import "pe"
rule MAL_CRIME_RAT_WIN_PE_GodRat_Aug25: GodRAT {
   meta:
      description = "Detects GodRAT malware targeting Windows systems"
      author = "Arda Buyukkaya"
      date = "2025-08-23"
      family = "GodRAT"
      reference = "https://securelist.com/godrat/117119/"
      tags = "RAT, Windows, GodRAT, Gh0st RAT, GETGOD"
      victims = "Financial services"
      sha256 = "154e800ed1719dbdcb188c00d5822444717c2a89017f2d12b8511eeeda0c2f41"
   strings:
            $winrt_txt = "C++/WinRT version" ascii wide nocase

            $api_blob = {
         4E 74 43 72 65 61 74 65 53 65 63 74 69 6F 6E 00                                   4E 74 4D 61 70 56 69 65 77 4F 66 53 65 63 74 69 6F 6E 00 00                       4E 74 55 6E 6D 61 70 56 69 65 77 4F 66 53 65 63 74 69 6F 6E 00 00 00 00        }

                              
            $ld_movups = { 0F 10 05 ?? ?? ?? ?? }        $ld_movq = { F3 0F 7E 05 ?? ?? ?? ?? }  
            $st_movups = { 0F 11 85 ?? ?? ?? ?? }        $st_movq = { 66 0F D6 85 ?? ?? ?? ?? }  
            $scan_loop = { 8A 01 41 84 C0 75 F9 }  
            $cmp_len_770 = { 81 FF 70 07 00 00 0F 82 ?? ?? ?? ?? }        $cmp_len_76C = { 81 FF 6C 07 00 00 0F 82 ?? ?? ?? ?? }     condition:
      pe.is_pe and
      filesize <= 10MB and
      (
                  (
            $winrt_txt and
            (
               pe.imphash() == "0f4b0270c84616ce594b6a84c47a7717"
            )
         )
         or
                  (
                        ($ld_movups or $ld_movq) and
                        (
               (#st_movups >= 2) or
               (#st_movq >= 2) or
               (#st_movups >= 1 and #st_movq >= 1)
            ) and
                        $scan_loop and
                        $api_blob and
                        ($cmp_len_770 or $cmp_len_76C)
         )
         or
                           pe.imphash() == "ee5ea868d8233000216e7b29bc8cb4e2"
      )
}