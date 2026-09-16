rule TTP_XOR_WriteProcessMemory_e00a {
  strings:
    $key_e00a = { b7 78 [2] 85 5a [2] 83 6f [2] ad 6f [2] 92 73 }

  condition:
    any of them
}