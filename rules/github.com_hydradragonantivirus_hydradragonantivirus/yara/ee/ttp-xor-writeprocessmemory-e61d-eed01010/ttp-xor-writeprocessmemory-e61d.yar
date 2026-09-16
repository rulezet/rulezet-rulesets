rule TTP_XOR_WriteProcessMemory_e61d {
  strings:
    $key_e61d = { b1 6f [2] 83 4d [2] 85 78 [2] ab 78 [2] 94 64 }

  condition:
    any of them
}