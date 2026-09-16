rule TTP_XOR_WriteProcessMemory_9f8a {
  strings:
    $key_9f8a = { c8 f8 [2] fa da [2] fc ef [2] d2 ef [2] ed f3 }

  condition:
    any of them
}