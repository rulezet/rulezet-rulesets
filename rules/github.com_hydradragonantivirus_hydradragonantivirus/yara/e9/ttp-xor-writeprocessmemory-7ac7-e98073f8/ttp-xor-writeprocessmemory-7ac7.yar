rule TTP_XOR_WriteProcessMemory_7ac7 {
  strings:
    $key_7ac7 = { 2d b5 [2] 1f 97 [2] 19 a2 [2] 37 a2 [2] 08 be }

  condition:
    any of them
}