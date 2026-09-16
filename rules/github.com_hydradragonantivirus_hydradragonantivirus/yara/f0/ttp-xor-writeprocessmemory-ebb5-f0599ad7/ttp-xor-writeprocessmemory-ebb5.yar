rule TTP_XOR_WriteProcessMemory_ebb5 {
  strings:
    $key_ebb5 = { bc c7 [2] 8e e5 [2] 88 d0 [2] a6 d0 [2] 99 cc }

  condition:
    any of them
}