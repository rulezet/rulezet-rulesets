rule TTP_XOR_WriteProcessMemory_e27a {
  strings:
    $key_e27a = { b5 08 [2] 87 2a [2] 81 1f [2] af 1f [2] 90 03 }

  condition:
    any of them
}