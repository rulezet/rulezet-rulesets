rule TTP_XOR_WriteProcessMemory_690b {
  strings:
    $key_690b = { 3e 79 [2] 0c 5b [2] 0a 6e [2] 24 6e [2] 1b 72 }

  condition:
    any of them
}