rule TTP_XOR_WriteProcessMemory_838f {
  strings:
    $key_838f = { d4 fd [2] e6 df [2] e0 ea [2] ce ea [2] f1 f6 }

  condition:
    any of them
}