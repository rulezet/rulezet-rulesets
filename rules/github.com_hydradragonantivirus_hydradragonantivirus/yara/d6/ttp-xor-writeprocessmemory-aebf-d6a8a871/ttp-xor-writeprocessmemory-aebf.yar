rule TTP_XOR_WriteProcessMemory_aebf {
  strings:
    $key_aebf = { f9 cd [2] cb ef [2] cd da [2] e3 da [2] dc c6 }

  condition:
    any of them
}