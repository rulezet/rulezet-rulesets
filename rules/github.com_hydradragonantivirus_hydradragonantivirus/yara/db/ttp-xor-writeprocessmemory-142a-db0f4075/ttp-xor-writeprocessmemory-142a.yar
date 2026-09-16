rule TTP_XOR_WriteProcessMemory_142a {
  strings:
    $key_142a = { 43 58 [2] 71 7a [2] 77 4f [2] 59 4f [2] 66 53 }

  condition:
    any of them
}