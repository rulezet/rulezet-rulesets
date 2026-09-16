rule TTP_XOR_WriteProcessMemory_cf0f {
  strings:
    $key_cf0f = { 98 7d [2] aa 5f [2] ac 6a [2] 82 6a [2] bd 76 }

  condition:
    any of them
}