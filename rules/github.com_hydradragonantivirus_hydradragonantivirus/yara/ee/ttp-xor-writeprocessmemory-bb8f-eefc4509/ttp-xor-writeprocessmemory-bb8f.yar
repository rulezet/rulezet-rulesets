rule TTP_XOR_WriteProcessMemory_bb8f {
  strings:
    $key_bb8f = { ec fd [2] de df [2] d8 ea [2] f6 ea [2] c9 f6 }

  condition:
    any of them
}