rule TTP_XOR_WriteProcessMemory_ab8f {
  strings:
    $key_ab8f = { fc fd [2] ce df [2] c8 ea [2] e6 ea [2] d9 f6 }

  condition:
    any of them
}