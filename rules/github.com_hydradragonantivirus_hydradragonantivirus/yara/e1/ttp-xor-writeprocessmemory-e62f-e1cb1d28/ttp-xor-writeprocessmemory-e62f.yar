rule TTP_XOR_WriteProcessMemory_e62f {
  strings:
    $key_e62f = { b1 5d [2] 83 7f [2] 85 4a [2] ab 4a [2] 94 56 }

  condition:
    any of them
}