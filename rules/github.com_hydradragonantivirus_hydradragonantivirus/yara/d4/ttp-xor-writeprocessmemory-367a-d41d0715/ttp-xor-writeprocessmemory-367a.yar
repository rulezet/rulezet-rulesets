rule TTP_XOR_WriteProcessMemory_367a {
  strings:
    $key_367a = { 61 08 [2] 53 2a [2] 55 1f [2] 7b 1f [2] 44 03 }

  condition:
    any of them
}