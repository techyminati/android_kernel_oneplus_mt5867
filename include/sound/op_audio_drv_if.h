
#if !defined(_OP_AUDIO_DRV_IF_H_)
#define _OP_AUDIO_DRV_IF_H_

/* for snd mode*/

enum _OP_AUD_SND_MODE {
    OP_AUD_SND_MODE_UNKNOWN = -1,
    OP_AUD_SND_MODE_MIN_VAL = 0,
    OP_AUD_SND_MODE_STANDARD = OP_AUD_SND_MODE_MIN_VAL,
    OP_AUD_SND_MODE_THEATER,
    OP_AUD_SND_MODE_MUSIC,
    OP_AUD_SND_MODE_NEWS,
    OP_AUD_SND_MODE_SPORTS,
    OP_AUD_SND_MODE_GAME,
    OP_AUD_SND_MODE_USER,
    OP_AUD_SND_MODE_COUNT,
    OP_AUD_SND_MODE_MAX_VAL = OP_AUD_SND_MODE_COUNT - 1,
};
typedef enum _OP_AUD_SND_MODE OP_AUD_SND_MODE_t;

#define OP_AUD_SND_EQ_USER_PARAM_BAND_MASK_1            (1<<0)
#define OP_AUD_SND_EQ_USER_PARAM_BAND_MASK_2            (1<<1)
#define OP_AUD_SND_EQ_USER_PARAM_BAND_MASK_3            (1<<2)
#define OP_AUD_SND_EQ_USER_PARAM_BAND_MASK_4            (1<<3)
#define OP_AUD_SND_EQ_USER_PARAM_BAND_MASK_5            (1<<4)
#define OP_AUD_SND_EQ_USER_PARAM_BAND_MASK_6            (1<<5)
#define OP_AUD_SND_EQ_USER_PARAM_BAND_MASK_7            (1<<6)
#define OP_AUD_SND_EQ_USER_PARAM_BAND_MASK_8            (1<<7)
#define OP_AUD_SND_EQ_USER_PARAM_BAND_MASK_9            (1<<8)

struct _OP_AUD_SND_EQ_USER_PARAM {
    uint16_t nFieldMask;
    int16_t nBand1Gain;
    int16_t nBand2Gain;
    int16_t nBand3Gain;
    int16_t nBand4Gain;
    int16_t nBand5Gain;
    int16_t nBand6Gain;
    int16_t nBand7Gain;
    int16_t nBand8Gain;
    int16_t nBand9Gain;
};
typedef struct _OP_AUD_SND_EQ_USER_PARAM OP_AUD_SND_EQ_USER_PARAM_t;

/* sub cmd id of AMP_CTRL_DBG_APPLY_PASSED_PARAM */
#define     ACD_PASSED_PARAM_ID_INIT_SEQ_AD85050    1

struct __attribute__ ((aligned (4), packed)) _AC_DBG_PASSED_PARAM 
{
   uint8_t nParamMetaId;
#if (__SIZEOF_POINTER__ == 8)
   void * puserParamData;
#elif (__SIZEOF_POINTER__ == 4)
   void * puserParamData;
   uint32_t puserParamData_padding;
#endif
   uint32_t nParamSize;
}
;
typedef struct _AC_DBG_PASSED_PARAM AC_DBG_PASSED_PARAM_t;

//sub command id for MTAL_IO_AUDDEC_AMP_CTRL
#define AMP_CTRL_SET_EQ_MODE                        1
#define AMP_CTRL_SET_EQ_USER_PARAM                  2
#define AMP_CTRL_SET_LINE_OUT_MUTE                  3
#define AMP_CTRL_SET_AllowDriverRwTAS58xxI2c        4
#define AMP_CTRL_GET_AllowDriverRwTAS58xxI2c        5
/* mute for a while if DAP sw changed */
#define AMP_CTRL_MUTE_FOR_DOLBY_ATMOS_SW            6
#define AMP_CTRL_MUTE_FOR_CHANGE_SOUND_MODE         7
#define AMP_CTRL_MUTE_FOR_CHANGE_AUD_OUT            8
/* ioctl cmd to do smooth unmute for AMP driver */
#define AMP_CTRL_SET_SMOOTH_UNMUTE                  9
#define AMP_CTRL_DBG_APPLY_PASSED_PARAM             10
#define AMP_CTRL_MUTE_FOR_ANDROID_AUD_HAL           11

/* params passed from an upper layer */
#define USER_EQ_BAND1_CENTER_FREQ_HZ                 100
#define USER_EQ_BAND2_CENTER_FREQ_HZ                 200
#define USER_EQ_BAND3_CENTER_FREQ_HZ                 500
#define USER_EQ_BAND4_CENTER_FREQ_HZ                 1000
#define USER_EQ_BAND5_CENTER_FREQ_HZ                 (2*1000)
#define USER_EQ_BAND6_CENTER_FREQ_HZ                 (5*1000)
#define USER_EQ_BAND7_CENTER_FREQ_HZ                 (10*1000)
#define USER_EQ_BAND8_CENTER_FREQ_HZ                 (60)
#define USER_EQ_BAND9_CENTER_FREQ_HZ                 (15*1000)

/* used by kernel driver modules */
int MI_AOUT_AmpCtrl_SetEqMode(const uint8_t nEqMode);
int MI_AOUT_AmpCtrl_SetEqUserParam(OP_AUD_SND_EQ_USER_PARAM_t * pOpAudSndEqUserParam);
int MI_AOUT_AmpCtrl_DbgApplyPassedParam(AC_DBG_PASSED_PARAM_t * pAcDbgPassedParam);

#endif  /* !defined(_OP_AUDIO_DRV_IF_H_) */

