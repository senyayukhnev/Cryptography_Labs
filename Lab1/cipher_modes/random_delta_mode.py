"""RANDOM_DELTA Mode with parallelization"""

import secrets
from typing import BinaryIO
from .base_mode import BaseCipherMode
from Lab1.utility.utility import pad, unpad, split_blocks, xor_bytes


class RandomDeltaMode(BaseCipherMode):
    """RANDOM_DELTA: C_i = E_K(P_i XOR IV_i) where IV_i = IV_{i-1} + Delta"""

    def _worker_decrypt(self, block: bytes):
        return self.primitive.decrypt_block(block)

    def _split_iv_delta(self, combined: bytes) -> tuple[bytes, int]:
        """Split combined data into IV and delta"""
        bs = self.block_size
        iv = combined[:bs]
        delta_bytes = combined[bs:]
        delta = int.from_bytes(delta_bytes, byteorder='big')
        return iv, delta

    def _increment_iv(self, iv: bytes, delta: int) -> bytes:
        """Increment IV by delta"""
        iv_int = int.from_bytes(iv, byteorder='big')
        new_iv_int = (iv_int + delta) & ((1 << (len(iv) * 8)) - 1)  # Wrap around
        return new_iv_int.to_bytes(len(iv), byteorder='big')

    def encrypt_bytes(self, data: bytes) -> bytes:
        bs = self.block_size
        padded = pad(data, bs, self.padding)

        # Generate random IV and initial delta (each full block)
        iv = secrets.token_bytes(bs)
        initial_delta_bytes = secrets.token_bytes(bs)
        combined = iv + initial_delta_bytes  # 2 blocks total

        # Convert delta to integer
        delta = int.from_bytes(initial_delta_bytes, byteorder='big')

        current_iv = iv
        output_parts = [combined]

        for p_block in split_blocks(padded, bs):
            # XOR plaintext with current IV
            xored = xor_bytes(p_block, current_iv)
            # Encrypt
            c_block = self.primitive.encrypt_block(xored)
            output_parts.append(c_block)
            # Update IV: add delta
            current_iv = self._increment_iv(current_iv, delta)

        return b"".join(output_parts)

    def decrypt_bytes(self, data: bytes) -> bytes:
        bs = self.block_size

        if len(data) < bs * 2:
            raise ValueError("Ciphertext too short for RANDOM_DELTA mode")

        # Extract combined IV+delta (2 blocks)
        combined = data[:bs * 2]
        ciphertext = data[bs * 2:]

        if len(ciphertext) % bs != 0:
            raise ValueError("Invalid ciphertext length for RANDOM_DELTA mode")

        # Split into IV and delta
        iv, delta = self._split_iv_delta(combined)

        # Prepare blocks for parallel decryption
        cipher_blocks = list(split_blocks(ciphertext, bs))

        # Decrypt all blocks in parallel
        decrypted_blocks = list(self._executor.map(self._worker_decrypt, cipher_blocks))

        # Reconstruct plaintext with IV progression
        current_iv = iv
        plaintext_parts = []

        for dec_block in decrypted_blocks:
            # XOR decrypted block with current IV to get plaintext
            plaintext_parts.append(xor_bytes(dec_block, current_iv))
            # Update IV for next block
            current_iv = self._increment_iv(current_iv, delta)

        return unpad(b"".join(plaintext_parts), bs, self.padding)

    def encrypt_file(self, fin: BinaryIO, fout: BinaryIO, chunk_size: int):
        bs = self.block_size

        # Generate random IV and initial delta (each full block)
        iv = secrets.token_bytes(bs)
        initial_delta_bytes = secrets.token_bytes(bs)
        combined = iv + initial_delta_bytes
        delta = int.from_bytes(initial_delta_bytes, byteorder='big')

        fout.write(combined)
        current_iv = iv
        carry = b""

        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break

            data = carry + chunk
            full_len = (len(data) // bs) * bs
            full, carry = data[:full_len], data[full_len:]

            for p_block in split_blocks(full, bs):
                xored = xor_bytes(p_block, current_iv)
                c_block = self.primitive.encrypt_block(xored)
                fout.write(c_block)
                current_iv = self._increment_iv(current_iv, delta)

        # Handle remaining data with padding
        for p_block in split_blocks(pad(carry, bs, self.padding), bs):
            xored = xor_bytes(p_block, current_iv)
            c_block = self.primitive.encrypt_block(xored)
            fout.write(c_block)
            current_iv = self._increment_iv(current_iv, delta)

    def decrypt_file(self, fin: BinaryIO, fout: BinaryIO, chunk_size: int):
        bs = self.block_size

        combined = fin.read(bs * 2)
        if len(combined) != bs * 2:
            raise ValueError("Ciphertext too short for RANDOM_DELTA mode")

        iv, delta = self._split_iv_delta(combined)

        current_iv = iv
        carry = b""
        hold = None

        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break

            data = carry + chunk
            full_len = (len(data) // bs) * bs
            full, carry = data[:full_len], data[full_len:]

            if full:
                cipher_blocks = list(split_blocks(full, bs))
                decrypted = list(self._executor.map(self._worker_decrypt, cipher_blocks))

                for i, dec_block in enumerate(decrypted):
                    plaintext_block = xor_bytes(dec_block, current_iv)

                    if hold is not None:
                        fout.write(hold)
                    hold = plaintext_block
                    current_iv = self._increment_iv(current_iv, delta)

        if carry:
            raise ValueError("Invalid ciphertext length for RANDOM_DELTA mode")

        if hold is not None:
            fout.write(unpad(hold, bs, self.padding))