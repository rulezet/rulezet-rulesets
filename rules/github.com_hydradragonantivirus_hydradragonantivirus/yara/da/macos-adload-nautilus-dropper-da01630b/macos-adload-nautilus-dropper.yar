rule macos_adload_nautilus_dropper {
  meta:
    description = "MACOS.ADLOAD"

  strings:
    $shebang = "#!"

    $string_1 = "mktemp -t"
    $string_2 = { 74 61 69 6c [1-2] 2d 63 }
    $string_3 = { 24 30 [1-3] 7c [1-3] 66 75 6e 7a 69 70 [1-3] 2d [6-12] 3e [1-3] 24 }
    $string_4 = { 63 68 6d 6f 64 [1-3] 2b 78 }
    $string_5 = { 6b 69 6c 6c 61 6c 6c [1-3] 54 65 72 6d 69 6e 61 6c }

    $string_6 = { 50 4b 03 04 14 }

  condition:
    filesize < 100KB and $shebang at 0 and all of ($string*)
}