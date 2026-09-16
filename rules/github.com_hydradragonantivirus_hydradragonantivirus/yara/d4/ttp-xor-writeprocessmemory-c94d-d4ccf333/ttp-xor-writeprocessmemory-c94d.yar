rule TTP_XOR_WriteProcessMemory_c94d {
  strings:
    $key_c94d = { 9e 3f [2] ac 1d [2] aa 28 [2] 84 28 [2] bb 34 }

  condition:
    any of them
}