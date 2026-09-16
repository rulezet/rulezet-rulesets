rule TTP_XOR_WriteProcessMemory_fcca {
  strings:
    $key_fcca = { ab b8 [2] 99 9a [2] 9f af [2] b1 af [2] 8e b3 }

  condition:
    any of them
}