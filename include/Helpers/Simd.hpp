#pragma once

#include <cstdint>
#include <emmintrin.h>
#include <smmintrin.h>
#include <xmmintrin.h>
#if defined(_MSC_VER) || defined(__x86_64__) || defined(__i386__)
#include <immintrin.h> // x86 SIMD
#elif
#error "this file isnt supported by this architecture"
#endif

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"

namespace HttpServer
{
  namespace Simd::Defaults // for when vectors aint supported :(
  {
    inline __attribute__((always_inline)) uint64_t cvtepu_u16(const uint32_t &val)
    {
      return (static_cast<uint64_t>(val & 0xFFFF0000) << 16U) | (static_cast<uint64_t>(val & 0x0000FFFF));
    }

  } // namespace Simd::Defaults

  namespace Simd
  {
    inline uint32_t HorizontalReduction2byte(const uint8_t *start, const uint8_t *end);

#if defined(__AVX512BW__) && defined(__AVX512VL__)

    uint32_t HorizontalReduction2byte(const uint8_t *start, const uint8_t *end)
    {
    }

#elif defined(__AVX2__)

    uint32_t HorizontalReduction2byte(const uint8_t *start, const uint8_t *end)
    {
      constexpr auto M_BYTE_JMP = 16;
      constexpr auto N_BYTE_JMP = M_BYTE_JMP * 4;

      uint64_t d_sum_u32 = 0;

      __m256i sum_vec = _mm256_setzero_si256();
      for(; start + N_BYTE_JMP <= end; start += N_BYTE_JMP) // mom says we have vectors at home :0 ... vectors at home :
      {
        const __m128i packed_u16_0 = _mm_loadu_si128(reinterpret_cast<const __m128i_u *>(start));
        const __m128i packed_u16_1 = _mm_loadu_si128(reinterpret_cast<const __m128i_u *>(start + 16));
        const __m128i packed_u16_2 = _mm_loadu_si128(reinterpret_cast<const __m128i_u *>(start + 32));
        const __m128i packed_u16_3 = _mm_loadu_si128(reinterpret_cast<const __m128i_u *>(start + 48));

        const __m256i zext_u32_0 = _mm256_cvtepu16_epi32(packed_u16_0);
        const __m256i zext_u32_1 = _mm256_cvtepu16_epi32(packed_u16_1);
        const __m256i zext_u32_2 = _mm256_cvtepu16_epi32(packed_u16_2);
        const __m256i zext_u32_3 = _mm256_cvtepu16_epi32(packed_u16_3);

        sum_vec = _mm256_add_epi32(sum_vec, _mm256_add_epi32(_mm256_add_epi32(zext_u32_0, zext_u32_1), _mm256_add_epi32(zext_u32_2, zext_u32_3)));
      }

      for(; start + M_BYTE_JMP <= end; start += M_BYTE_JMP)
      {
        const __m128i packed_u16 = _mm_loadu_si128(reinterpret_cast<const __m128i_u *>(start));
        sum_vec = _mm256_add_epi32(sum_vec, _mm256_cvtepu16_epi32(packed_u16));
      }

      const __m128i top = _mm256_extractf128_si256(sum_vec, 1);
      const __m128i bot = _mm256_castsi256_si128(sum_vec);
      const __m128i sum = _mm_add_epi32(top, bot);

      const __m128i sum_shf_64 = _mm_shuffle_epi32(sum, _MM_SHUFFLE(0, 1, 2, 3));
      const __m128i sum_64 = _mm_add_epi32(sum, sum_shf_64);

      const __m128i sum_shf_32 = _mm_shuffle_epi32(sum_64, _MM_SHUFFLE(0, 0, 0, 1));
      const __m128i sum_32 = _mm_add_epi32(sum_64, sum_shf_32);

      d_sum_u32 += static_cast<uint64_t>(_mm_cvtsi128_si32(sum_32));

      for(; start + 2 <= end; start += 2)
      {
        d_sum_u32 += *reinterpret_cast<const uint16_t *>(start);
      }

      if(start < end)
      {
        d_sum_u32 += *start;
      }

      return static_cast<uint32_t>(d_sum_u32 >> 32U) + static_cast<uint32_t>(d_sum_u32 & 0xFFFFFFFF);
    }

#else // prehistoric age computer or deliverate ???  we'll use default's with my manual 64 bit (hopefully) SIMD ;)

    uint32_t HorizontalReduction2byte(const uint8_t *start, const uint8_t *end)
    {
      constexpr auto N_BYTE_JMP = 16;

      uint64_t d_sum_u32 = 0;

      for(; start + N_BYTE_JMP <= end; start += N_BYTE_JMP) // mom says we have vectors at home :0 ... vectors at home :
      {
        const uint32_t dwrd_0 = *reinterpret_cast<const uint32_t *>(start);
        const uint32_t dwrd_1 = *reinterpret_cast<const uint32_t *>(start + 4);
        const uint32_t dwrd_2 = *reinterpret_cast<const uint32_t *>(start + 8);
        const uint32_t dwrd_3 = *reinterpret_cast<const uint32_t *>(start + 12);

        d_sum_u32 += Simd::Defaults::cvtepu_u16(dwrd_0);
        d_sum_u32 += Simd::Defaults::cvtepu_u16(dwrd_1);
        d_sum_u32 += Simd::Defaults::cvtepu_u16(dwrd_2);
        d_sum_u32 += Simd::Defaults::cvtepu_u16(dwrd_3);
      }

      for(; start + 2 <= end; start += 2) // mom says we have vectors at home :0 ... vectors at home :
      {
        d_sum_u32 += *reinterpret_cast<const uint16_t *>(start);
      }

      if(start < end)
      {
        d_sum_u32 += *start;
      }

      return static_cast<uint32_t>(d_sum_u32) + static_cast<uint32_t>(d_sum_u32 >> 32U);
    }

#endif

  } // namespace Simd
} // namespace HttpServer

#pragma GCC diagnostic pop
//
//
