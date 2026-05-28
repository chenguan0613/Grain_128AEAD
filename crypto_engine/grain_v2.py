class Grain128AEADv2:
    def __init__(self):
        self.NFSR=[0]*128
        self.LFSR=[0]*128
        self.key_bits=[]
    def load_key_and_iv(self,key_bits,iv_bits):
        self.key_bits=key_bits.copy()
        self.NFSR=key_bits.copy()
        self.LFSR=iv_bits.copy()
        self.LFSR[:96]=iv_bits.copy()
        self.LFSR[96:127]=[1]*31
        self.LFSR[127]=0
    def _L(self):
        s=self.LFSR
        return s[0]^s[7]^s[38]^s[70]^s[81]^s[96]
    def _F(self):
        b=self.NFSR
        return (b[0]^b[26]^b[56]^b[91]^b[96]^(b[3]&b[67])
                ^(b[11]&b[13])^(b[17]&b[18])^(b[27]&b[59])
                ^(b[40]&b[48])^(b[61]&b[65])^(b[68] & b[84])
                ^(b[22]&b[24]&b[25])^(b[70] & b[78] & b[82])
                ^(b[88]&b[92]&b[93]&b[95]))
    def _pre_output(self):
        s=self.LFSR
        b=self.NFSR
        h_x=(b[12]&s[8])^(s[13]&s[20])^(b[95]&s[42])^(s[60]&s[79])^(b[12]&b[95]&s[94])
        return h_x^s[93]^b[2]^b[15]^b[36]^b[45]^b[64]^b[73]^b[89]
    
    def initialise(self):
        for t in range(512):
            l_val=self._L()
            f_val=self._F()
            y_t=self._pre_output()
            s_127=0
            b_127=0
            if t<=319:
                s_127=l_val^y_t
                b_127=self.LFSR[0]^f_val^y_t
            elif 320<=t<=383:
                s_127=l_val^y_t^self.key_bits[t-256]
                b_127=self.LFSR[0]^f_val^y_t^self.key_bits[t-320]
            elif 384<=t<=511:
                s_127=l_val
                b_127=self.LFSR[0]^f_val
            self.LFSR.pop(0)
            self.LFSR.append(s_127)
            self.NFSR.pop(0)
            self.NFSR.append(b_127)
    def encrypt(self,message_bits):
        L=len(message_bits)
        ciphertext_bits=[0]*L
        for t in range(2*L):
            if t%2==0:
                y_t=self._pre_output()
                i=t//2
                z_i=y_t
                ciphertext_bits[i]=message_bits[i]^z_i
            l_val=self._L()
            f_val=self._F()
            s_127=l_val
            b_127=self.LFSR[0]^f_val
            self.LFSR.pop(0)
            self.LFSR.append(s_127)
            self.NFSR.pop(0)
            self.NFSR.append(b_127)
        return ciphertext_bits
    def decrypt(self,ciphertext_bits):
        L=len(ciphertext_bits)
        message=[0]*L
        for t in range(2*L):
            if t%2==0:
                y_t=self._pre_output()
                i=t//2
                z_i=y_t
                message[i]=ciphertext_bits[i]^z_i
            l_val=self._L()
            f_val=self._F()
            s_127=l_val
            b_127=self.LFSR[0]^f_val
            self.LFSR.pop(0)
            self.LFSR.append(s_127)
            self.NFSR.pop(0)
            self.NFSR.append(b_127)
        return message
                
