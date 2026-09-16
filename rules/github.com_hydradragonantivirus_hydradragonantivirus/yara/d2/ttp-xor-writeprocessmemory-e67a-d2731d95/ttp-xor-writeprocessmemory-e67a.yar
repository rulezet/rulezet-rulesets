rule TTP_XOR_WriteProcessMemory_e67a {
  strings:
    $key_e67a = { b1 08 [2] 83 2a [2] 85 1f [2] ab 1f [2] 94 03 }

  condition:
    any of them
}