rule TTP_XOR_WriteProcessMemory_e61a {
  strings:
    $key_e61a = { b1 68 [2] 83 4a [2] 85 7f [2] ab 7f [2] 94 63 }

  condition:
    any of them
}