# RSA blind signature anonymous voting (basic proof of concept on Ruby)
# 15.04.2016 - Yura Babak /// yura.des@gmail.com
# https://github.com/the-power-of-trust/RSA-blind-signature
# tested on Ruby 2.0
require 'openssl'


def blinding_factor(key)
								puts '- blinding_factor'
	n = key.params['n'].to_i
								puts "n: #{n}"
	r = (rand*(n-1)).to_i
								puts "r: #{r}"
	#. greatest common divisor
	r += 1 while r.gcd(n) !=1
								puts "r: #{r}"
								puts '- /blinding_factor' 
	r
end

def text_to_int(text)
	bitmap = '1'+text.unpack('B*')[0]
	bitmap.to_i(2)
end

def int_to_text(int)
	bitmap = int.to_i.to_s(2)
	[bitmap.sub(/^1/, '')].pack('B*')
end

def blind(msg, key)
								puts '-- blind'
								puts "msg: #{msg}"
	r = blinding_factor(key)
								puts "r: #{r}"
	msg_int = text_to_int(msg)
								puts "msg_int: #{msg_int}"
								puts "msg_int < n: #{msg_int < key.params['n']}"
								puts "msg_int_text: #{int_to_text(msg_int)}"
	# m' = mr^e (mod n)
	msg_int_blinded = msg_int * r.to_bn.mod_exp(key.params['e'], key.params['n']) % key.params['n']
								puts "msg_int_blinded: #{msg_int_blinded}"
								puts '-- /blind'
	return msg_int_blinded, r
end

def unblind(blinded_msg, r, key)
								puts '-- unblind'
								puts "r: #{r}"
	# sm = sm' * r^-1 (mod n)
	msg = blinded_msg * r.to_bn.mod_inverse(key.params['n']) % key.params['n']
								puts "msg: #{msg}"
								puts '-- /unblind'
	msg
end

def sign(msg, key)
	# sm = m^d (mod n)
	msg.to_bn.mod_exp(key.params['d'], key.params['n']) % key.params['n']
end

def verify(msg_signed, msg, key)
	# sm'^e (mod n) == m'
	verify_res = msg_signed.to_bn.mod_exp(key.params['e'], key.params['n']) % key.params['n']
								puts "verify_res: #{verify_res}"
								puts "msg:        #{msg}"
	matches = verify_res == msg
								puts "matches: #{matches}"
								puts "signed_text: #{int_to_text(verify_res)}"
end

								puts '- RSA key'
# RSA key
bits = 512
key = OpenSSL::PKey::RSA.new(bits)
								puts "public e: #{key.params['e']}"
								puts "private d: #{key.params['d']}"
								puts "mod n: #{key.params['n']}"
								puts '- /RSA key'
								puts '- msg'
# msg
msg = '+1 vote for candidate A'
								puts "msg: #{msg}"
# 224 < 256 (512/2)
digest = OpenSSL::Digest::SHA224.hexdigest(msg)
								puts "digest: #{digest}"
								puts '- /msg'
								puts
# m' = mr^e (mod n)
msg_int_blinded, r = blind(digest, key)
								puts
# sm' = m'^d (mod n)
msg_int_blinded_signed = sign(msg_int_blinded, key)
								puts "msg_int_blinded_signed: #{msg_int_blinded_signed}"
# verify(msg_int_blinded_signed, msg_int_blinded, key)
								puts
# sm = sm' * r^-1 (mod n)
msg_int_signed = unblind(msg_int_blinded_signed, r, key)
								puts
msg_int = text_to_int(digest)
verify(msg_int_signed, msg_int, key)




