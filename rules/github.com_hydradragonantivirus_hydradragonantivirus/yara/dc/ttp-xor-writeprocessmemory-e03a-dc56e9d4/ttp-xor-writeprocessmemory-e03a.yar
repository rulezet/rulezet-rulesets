rule TTP_XOR_WriteProcessMemory_e03a {
  strings:
    $key_e03a = { b7 48 [2] 85 6a [2] 83 5f [2] ad 5f [2] 92 43 }

  condition:
    any of them
}