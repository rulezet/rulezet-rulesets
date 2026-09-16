rule TTP_XOR_WriteProcessMemory_7a11 {
  strings:
    $key_7a11 = { 2d 63 [2] 1f 41 [2] 19 74 [2] 37 74 [2] 08 68 }

  condition:
    any of them
}