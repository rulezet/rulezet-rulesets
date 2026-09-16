rule TTP_XOR_WriteProcessMemory_cf3f {
  strings:
    $key_cf3f = { 98 4d [2] aa 6f [2] ac 5a [2] 82 5a [2] bd 46 }

  condition:
    any of them
}