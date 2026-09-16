rule TTP_XOR_WriteProcessMemory_e61f {
  strings:
    $key_e61f = { b1 6d [2] 83 4f [2] 85 7a [2] ab 7a [2] 94 66 }

  condition:
    any of them
}