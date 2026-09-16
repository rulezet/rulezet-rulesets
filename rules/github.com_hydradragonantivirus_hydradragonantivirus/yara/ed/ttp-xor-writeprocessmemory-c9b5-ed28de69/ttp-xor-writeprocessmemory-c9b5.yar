rule TTP_XOR_WriteProcessMemory_c9b5 {
  strings:
    $key_c9b5 = { 9e c7 [2] ac e5 [2] aa d0 [2] 84 d0 [2] bb cc }

  condition:
    any of them
}