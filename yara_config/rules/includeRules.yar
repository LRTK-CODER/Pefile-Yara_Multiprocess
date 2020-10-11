// Utill Rules
// include "utill/header_signature_rules.yar"
// include "utill/suspicious_strings.yar"
// include "utill/ip.yar"
// include "utill/url.yar"
// include "utill/domain.yar"
// include "utill/base64.yar" 해당 룰에 적용되는 것이 많아서 문제
// include "email.yar" 정규 표현식 수정이 필요

// Anti Technology
// include "anti/antidebug.yar"
// include "anti/antivm.yar"
// include "anti/antivirus.yar"
// include "anti/antietc.yar"

// Capabilities
// include "capabilities/capabilities.yar"

// Packer Rules
include "packers/packer.yar"
include "packers/packer_compiler_signatures.yar"