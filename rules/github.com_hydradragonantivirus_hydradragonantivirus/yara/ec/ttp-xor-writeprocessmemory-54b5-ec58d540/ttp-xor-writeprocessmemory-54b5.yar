rule TTP_XOR_WriteProcessMemory_54b5 {
  strings:
    $key_54b5 = { 03 c7 [2] 31 e5 [2] 37 d0 [2] 19 d0 [2] 26 cc }

  condition:
    any of them
}