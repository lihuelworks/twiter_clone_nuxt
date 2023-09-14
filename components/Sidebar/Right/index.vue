<template>
    <div class="flex flex-col">
        <!-- Preview Card: What's happening -->
        <SidebarRightPreviewCard title="What's happening">
            <SidebarRightPreviewCardItem v-for="whatsHappening in whatsHappeningItems">
                <div>
                    <h2 class="font-bold text-gray-800 text-md dark:text-white">{{ whatsHappening.title }}</h2>
                    <p class="text-xs text-gray-400">{{ whatsHappening.count  }}</p>
                </div>
            </SidebarRightPreviewCardItem>
        </SidebarRightPreviewCard>
        <!-- Preview Card: What's happening -->
        <SidebarRightPreviewCard title="Who to follow">
            <SidebarRightPreviewCardItem v-for="whoToFollow in whoToFollowItems">
                <div class="flex flex-row items-center justify-between p-2">
                    <div class="flex flex-row">
                        <img class="w-10 h-10 rounded-full" 
                        :src="whoToFollow.image" :alt="`user image for ${whoToFollow.name}`"/>
                        <div class="flex flex-col ml-2">
                            <h1 class="text-sm font-bold text-gray-500 dark:text-white">{{ whoToFollow.name }}</h1>
                            <p class="text-xs text-gray-400">{{ whoToFollow.handle }}</p>
                        </div>
                    </div>
                    <div class="flex  h-full">
                        <button class="px-4 py-2 text-xs font-bold text-white dark:text-black bg-black dark:bg-white rounded-full">Follow</button>
                    </div>
                </div>
            </SidebarRightPreviewCardItem>
        </SidebarRightPreviewCard>
    </div>
</template>

<script setup>
const whatsHappeningItems = ref([
    {
        title: 'Boca vs River',
        count: '18.8k Tweets'
    },
    {
        title: 'Codeando',
        count: '8.8k Tweets'
    },
    {
        title: '#DefeCampeon',
        count: '500m Tweets'
    },
])

const whoToFollowItems = ref([
    {
        name: 'Carlos Gardel',
        handle: '@carlitosarg',
        image: 'https://picsum.photos/200/200'
    },
    {
        name: 'Messi',
        handle: '@lionel',
        image: 'https://picsum.photos/304/200/'
    },
    {
        name: 'Luisito Comunica',
        handle: '@luisitoelluisillo',
        image: 'https://picsum.photos/404/200'
    },
])
</script>

<style lang="scss" scoped>

</style>