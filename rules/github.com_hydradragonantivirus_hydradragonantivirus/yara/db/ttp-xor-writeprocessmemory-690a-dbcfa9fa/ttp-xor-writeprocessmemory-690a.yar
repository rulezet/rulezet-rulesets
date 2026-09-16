rule TTP_XOR_WriteProcessMemory_690a {
  strings:
    $key_690a = { 3e 78 [2] 0c 5a [2] 0a 6f [2] 24 6f [2] 1b 73 }

  condition:
    any of them
}