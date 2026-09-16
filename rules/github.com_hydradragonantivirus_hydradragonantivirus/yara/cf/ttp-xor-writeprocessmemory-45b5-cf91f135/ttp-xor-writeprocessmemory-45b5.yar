rule TTP_XOR_WriteProcessMemory_45b5 {
  strings:
    $key_45b5 = { 12 c7 [2] 20 e5 [2] 26 d0 [2] 08 d0 [2] 37 cc }

  condition:
    any of them
}