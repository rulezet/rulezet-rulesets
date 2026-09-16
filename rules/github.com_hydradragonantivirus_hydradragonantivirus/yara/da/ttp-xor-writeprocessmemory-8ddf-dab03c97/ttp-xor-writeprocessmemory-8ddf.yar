rule TTP_XOR_WriteProcessMemory_8ddf {
  strings:
    $key_8ddf = { da ad [2] e8 8f [2] ee ba [2] c0 ba [2] ff a6 }

  condition:
    any of them
}