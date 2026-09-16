rule TTP_XOR_WriteProcessMemory_fbb5 {
  strings:
    $key_fbb5 = { ac c7 [2] 9e e5 [2] 98 d0 [2] b6 d0 [2] 89 cc }

  condition:
    any of them
}