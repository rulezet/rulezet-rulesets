rule spam 
{
    meta:
    description = "Indicates spam-related activity"
    
    strings:
    $spam0000 = "invitation card" nocase
    $spam0002 = "shipping documents" nocase
    $spam0003 = "e-cards@hallmark.com" nocase
    $spam0004 = "invitations@twitter.com" nocase
    $spam0005 = "invitations@hi5.com" nocase
    $spam0006 = "order-update@amazon.com" nocase
    $spam0007 = "hallmark e-card" nocase
    $spam0008 = "invited you to twitter" nocase
    $spam0009 = "friend on hi5" nocase
    $spam000a = "shipping update for your amazon.com" nocase
    $spam000b = "rcpt to:" nocase
    $spam000c = "mail from:" nocase
    $spam000d = "smtp server" nocase 
    $spam000e = "mx record" nocase
    $spam000f = "cialis" nocase fullword
    $spam0010 = "pharma" nocase fullword
    $spam0011 = "casino" nocase fullword
    $spam0012 = "ehlo " nocase fullword
    $spam0013 = "from: " nocase fullword
    $spam0014 = "subject: " nocase fullword
    $spam0015 = "Content-Disposition: attachment;" nocase
    $spam0016 = "postcard" nocase fullword
    
    condition:
    3 of ($spam*)
}