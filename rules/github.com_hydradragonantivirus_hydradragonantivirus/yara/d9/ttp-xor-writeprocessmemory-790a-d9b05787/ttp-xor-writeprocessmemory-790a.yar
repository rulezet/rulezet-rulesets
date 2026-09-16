rule TTP_XOR_WriteProcessMemory_790a {
  strings:
    $key_790a = { 2e 78 [2] 1c 5a [2] 1a 6f [2] 34 6f [2] 0b 73 }

  condition:
    any of them
}