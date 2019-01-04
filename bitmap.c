#include "all.h"


struct bitmap_s *bitmap_init(struct bitmap_s *bmap)
{
	uint32_t i;
	
	memset(bmap, 0, sizeof(struct bitmap_s));

	for (i=0;i<1001;i++)
	{
		set_bitmap(bmap, i);
	}
	return bmap;
}

void set_bitmap(struct bitmap_s *lbmap, uint16_t u16_test)
{
	uint8_t top=(u16_test>>BIT_MAP_TOP_LSH)&(BIT_MAP_SEG_NUM-1);
	uint8_t mid=(u16_test>>BIT_MAP_ITER_LSH)&(BIT_MAP_PER_SEG-1);
	uint64_t map=1ull<<(u16_test & (BIT_MAP_PER_ITEM-1));
	uint32_t index = item_index(top,mid);

//	RUNNING_LOG_DEBUG("%s: top:%u mid:%u map:%#x\n", __FUNCTION__,top,mid,map);

	lbmap->bit_map[index] |= map;

	if (lbmap->bit_map[index] == 0xffffffffffffffffull)
	{
		lbmap->mid_index[top] |= (1ul << mid);

		if (lbmap->mid_index[top] == 0xffffffff)
			{
			lbmap->top_index |= (1ul << top);
			}
	}

//	RUNNING_LOG_INFO(">>> %s top: %u( mask: %#x) mid:%u (mask:%#x) map:%#llx\n", __FUNCTION__,
//		top, lbmap->top_index, mid, lbmap->mid_index[top], lbmap->bit_map[index]);
}

void clear_bitmap(struct bitmap_s *lbmap, uint16_t u16_test)
{
	uint8_t top=(u16_test>>BIT_MAP_TOP_LSH)&(BIT_MAP_SEG_NUM-1);
	uint8_t mid=(u16_test>>BIT_MAP_ITER_LSH)&(BIT_MAP_PER_SEG-1);
	uint64_t map=1ull<<(u16_test & (BIT_MAP_PER_ITEM-1));
	uint32_t index = item_index(top,mid);

	lbmap->bit_map[index] &= ~map;
	if (lbmap->bit_map[index] == 0)
	{
		lbmap->mid_index[top] &= ~(1ul << mid);
		if (lbmap->mid_index[top])
		{
			lbmap->top_index &= ~(1ul << top);
		}
	}

//	RUNNING_LOG_DEBUG(">>> %s top: %u( mask: %#x) mid:%u (mask:%#x) map:%#llx\n", __FUNCTION__,
//		top, lbmap->top_index, mid, lbmap->mid_index[top], lbmap->bit_map[index]);
}

void check_bitmap(struct bitmap_s *lbmap)
{
	uint32_t top,mid;
	uint32_t i,j;
	uint32_t index;

	if (!lbmap->top_index)
		return ;

	for (i=0; i<BIT_MAP_PER_SEG;i++){

//		if (!(lbmap->top_index & (1ul << i)))
//			continue;

		top = i;

		for (j=0;j<BIT_MAP_PER_ITEM;j++){
//			if (!(lbmap->mid_index[top] & (1ul << i)))
//				continue;

			mid=j;

			index = item_index(top,mid);

//			RUNNING_LOG_DEBUG(">>> top: %u( mask: %#x) mid:%u (mask:%#x) map:%#llx\n", top, lbmap->top_index, mid, lbmap->mid_index[mid], lbmap->bit_map[index]);
		}
	}
	return ;
}

int get_free_num(struct bitmap_s *lbmap, uint32_t begin, uint16_t *result)
{
	uint32_t top, mid;
	uint32_t i,j, k;
	uint16_t free;
	uint16_t index;

	top=((begin>>BIT_MAP_TOP_LSH)&(BIT_MAP_SEG_NUM-1));
	mid=(begin>>(BIT_MAP_ITER_LSH))&(BIT_MAP_PER_SEG-1);

//	RUNNING_LOG_DEBUG(">>> %s, find from %u top_msk:%#x top:%u mid:%u\n", __FUNCTION__, begin,lbmap->top_index, top, mid);

	if (lbmap->top_index==0xfffffffful)
		return -1;

	for (i=top; i<BIT_MAP_SEG_NUM;i++){

		if (lbmap->top_index & (1ul << i)){
			mid++;
			mid=mid%BIT_MAP_SEG_NUM;

			i++;
			i %= BIT_MAP_PER_SEG;
			continue;
		}

//		if (lbmap->mid_index[i] == 0xfffffffffful){
//			i++;
//			i %= BIT_MAP_PER_SEG;
//		}

		top = i;

		for (j=mid;j<BIT_MAP_ITEM_NUM;j++){
			if ((lbmap->mid_index[i] & (1ul << j)))
				continue;

			for (k=0; k<BIT_MAP_PER_ITEM; k++)
			{
				if (!(lbmap->bit_map[item_index(i,j)] & (1ull << k)))
					break;
			}

			mid = j;

			free = ((top & (BIT_MAP_SEG_NUM-1)) << BIT_MAP_TOP_LSH) | ((mid & (BIT_MAP_PER_SEG-1)) << BIT_MAP_ITER_LSH) | k;

			*result = free;

//			RUNNING_LOG_DEBUG(">>> top: %u( mask: %#x) mid:%u (mask:%#x) map:%#llx k: %u free:%u\n",
//				top, lbmap->top_index, mid, lbmap->mid_index[mid], lbmap->bit_map[item_index(top,mid)], k, free);

			return 0;
		}
	}

	return 0;
}

