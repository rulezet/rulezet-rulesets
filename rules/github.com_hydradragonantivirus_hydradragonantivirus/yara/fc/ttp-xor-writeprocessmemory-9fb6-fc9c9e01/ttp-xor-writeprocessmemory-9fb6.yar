rule TTP_XOR_WriteProcessMemory_9fb6 {
  strings:
    $key_9fb6 = { c8 c4 [2] fa e6 [2] fc d3 [2] d2 d3 [2] ed cf }

  condition:
    any of them
}