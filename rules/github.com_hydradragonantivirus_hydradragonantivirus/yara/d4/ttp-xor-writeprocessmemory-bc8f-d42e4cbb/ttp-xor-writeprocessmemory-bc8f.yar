rule TTP_XOR_WriteProcessMemory_bc8f {
  strings:
    $key_bc8f = { eb fd [2] d9 df [2] df ea [2] f1 ea [2] ce f6 }

  condition:
    any of them
}