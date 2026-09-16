rule TTP_XOR_WriteProcessMemory_cffe {
  strings:
    $key_cffe = { 98 8c [2] aa ae [2] ac 9b [2] 82 9b [2] bd 87 }

  condition:
    any of them
}