rule TTP_XOR_WriteProcessMemory_eab5 {
  strings:
    $key_eab5 = { bd c7 [2] 8f e5 [2] 89 d0 [2] a7 d0 [2] 98 cc }

  condition:
    any of them
}