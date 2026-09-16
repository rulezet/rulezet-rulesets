rule TTP_XOR_WriteProcessMemory_a8df {
  strings:
    $key_a8df = { ff ad [2] cd 8f [2] cb ba [2] e5 ba [2] da a6 }

  condition:
    any of them
}