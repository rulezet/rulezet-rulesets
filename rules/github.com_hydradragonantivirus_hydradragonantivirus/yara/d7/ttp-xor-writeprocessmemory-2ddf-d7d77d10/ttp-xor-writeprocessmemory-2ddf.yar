rule TTP_XOR_WriteProcessMemory_2ddf {
  strings:
    $key_2ddf = { 7a ad [2] 48 8f [2] 4e ba [2] 60 ba [2] 5f a6 }

  condition:
    any of them
}