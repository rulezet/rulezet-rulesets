event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
  {
  if ( /or.?1.?=.?1.?--/i in original_URI || /or.?1.?=.?1.?--/i in unescaped_URI )
    {
    local msg = fmt("SQLi attempt detected in URI from %s to %s: %s", c$id$orig_h, c$id$resp_h, original_URI);
    NOTICE([$note=SQLi_Attempt, $msg=msg, $conn=c]);
    }
  }