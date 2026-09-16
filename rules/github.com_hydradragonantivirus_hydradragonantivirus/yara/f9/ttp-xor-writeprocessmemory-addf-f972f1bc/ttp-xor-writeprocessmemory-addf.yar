rule TTP_XOR_WriteProcessMemory_addf {
  strings:
    $key_addf = { fa ad [2] c8 8f [2] ce ba [2] e0 ba [2] df a6 }

  condition:
    any of them
}