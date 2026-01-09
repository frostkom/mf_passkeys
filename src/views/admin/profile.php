<table class="secure-passkeys form-table">
	<tbody>
		<tr>
			<th>
				<label>{{ i18n.passkey_label }}</label>
			</th>
			<td>
				<div v-if="errorMessage" class="error">
					<p>{{ errorMessage }}</p>
				</div>

				<div v-if="successMessage" class="updated">
					<p>{{ successMessage }}</p>
				</div>

				<button
				:disabled="isLoading || addingPasskey || waitingAddPasskey || showSecurityKeyName || deletingPasskey"
				class="button add"
				v-if="is_owner"
				@click.prevent="addPasskey"
				@keydown.enter.prevent
				>
					<template v-if="addingPasskey">
						<i class="spinner is-active spin spinner-button"></i>
						{{ i18n.add_waiting_button }}
					</template>
					<template v-else-if="waitingAddPasskey">
						<i class="spinner is-active spin spinner-button"></i>
						{{ i18n.add_passkey_button }}
					</template>
					<template v-else>
						<span
						class="dashicons dashicons-plus"
						style="vertical-align: middle"
						></span>
						{{ i18n.add_passkey_button }}
					</template>
				</button>
				<table class="wp-list-table widefat striped">
					<thead>
						<tr>
<?php
							if(is_multisite())
							{
?>
								<th>{{ i18n.domain_column }}</th>
<?php
							}
?>
							<th>{{ i18n.last_used_column }}</th>
							<th>{{ i18n.created_at_column }}</th>
							<th v-if="is_owner || has_access"></th>
						</tr>
					</thead>
					<tbody>
						<tr v-for="item in list" :key="item.id" v-if="!isLoading">
<?php
							if(is_multisite())
							{
?>
								<td :data-label="i18n.domain_column">
									<template v-if="item.blog_id > 0">
										{{ item.blog_name }}
									</template>
									<template v-else> - </template>
								</td>
<?php
							}
?>
							<td :data-label="i18n.last_used_column">
								{{ item.last_used_at }}
							</td>
							<td :data-label="i18n.created_at_column">
								{{ item.created_at }}
							</td>
							<td
							:date-label="i18n.actions_column"
							v-if="is_owner || has_access"
							>
								<a
									href="#"
									@click.prevent="deletePasskey(item.id)"
									v-if="!deletingPasskey"
								>
									{{ i18n.delete }}
								</a>
								<span v-if="deletingPasskey && deletingId == item.id">
									{{ i18n.deleting }}
								</span>
							</td>
						</tr>
						<tr v-if="list.length == 0 && !isLoading">
							<td :colspan="is_owner || has_access ? 6 : 5" class="center">
								{{ i18n.no_records_found }}
							</td>
						</tr>
						<tr v-if="isLoading">
							<td
							:colspan="is_owner || has_access ? 6 : 5"
							class="center warning"
							style="text-align: center"
							>
								<i
									class="spinner is-active spin"
									style="text-align: center; margin: auto"
								></i>
							</td>
						</tr>
					</tbody>
				</table>
			</td>
		</tr>
	</tbody>
</table>