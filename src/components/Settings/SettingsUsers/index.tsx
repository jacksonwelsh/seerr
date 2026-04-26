import Alert from '@app/components/Common/Alert';
import Button from '@app/components/Common/Button';
import LabeledCheckbox from '@app/components/Common/LabeledCheckbox';
import LoadingSpinner from '@app/components/Common/LoadingSpinner';
import PageTitle from '@app/components/Common/PageTitle';
import PermissionEdit from '@app/components/PermissionEdit';
import QuotaSelector from '@app/components/QuotaSelector';
import useSettings from '@app/hooks/useSettings';
import globalMessages from '@app/i18n/globalMessages';
import defineMessages from '@app/utils/defineMessages';
import {
  ArrowDownOnSquareIcon,
  PlusIcon,
  TrashIcon,
} from '@heroicons/react/24/outline';
import { MediaServerType } from '@server/constants/server';
import type { HeaderAuthSettings, MainSettings } from '@server/lib/settings';
import axios from 'axios';
import { Field, FieldArray, Form, Formik } from 'formik';
import { useIntl } from 'react-intl';
import { useToasts } from 'react-toast-notifications';
import useSWR, { mutate } from 'swr';
import * as yup from 'yup';

const messages = defineMessages('components.Settings.SettingsUsers', {
  users: 'Users',
  userSettings: 'User Settings',
  userSettingsDescription: 'Configure global and default user settings.',
  toastSettingsSuccess: 'User settings saved successfully!',
  toastSettingsFailure: 'Something went wrong while saving settings.',
  loginMethods: 'Login Methods',
  loginMethodsTip: 'Configure login methods for users.',
  localLogin: 'Enable Local Sign-In',
  localLoginTip:
    'Allow users to sign in using their email address and password',
  mediaServerLogin: 'Enable {mediaServerName} Sign-In',
  mediaServerLoginTip:
    'Allow users to sign in using their {mediaServerName} account',
  atLeastOneAuth: 'At least one authentication method must be selected.',
  newPlexLogin: 'Enable New {mediaServerName} Sign-In',
  newPlexLoginTip:
    'Allow {mediaServerName} users to sign in without first being imported',
  movieRequestLimitLabel: 'Global Movie Request Limit',
  tvRequestLimitLabel: 'Global Series Request Limit',
  defaultPermissions: 'Default Permissions',
  defaultPermissionsTip: 'Initial permissions assigned to new users',
  disabledMediaServerLoginWarning:
    'Some users may not have a {applicationTitle} password set. Disabling {mediaServerName} sign-in could lock them out. Affected users will need to set a password from their profile or via a password reset link.',
  forwardAuth: 'Forward Auth (Trusted Proxy Headers)',
  forwardAuthDescription:
    'Trust authentication headers set by an upstream reverse proxy (e.g. Caddy forward_auth). When the request originates from a trusted proxy and the configured user header is present, the user is signed in automatically and provisioned if they do not yet exist.',
  forwardAuthEnabled: 'Enable Forward Auth',
  forwardAuthEnabledTip:
    'When enabled, requests from trusted proxies that include the configured user header will bypass the sign-in screen.',
  trustedProxiesEmptyWarning:
    'No proxies are trusted yet. Loopback (127.0.0.0/8 and ::1) is always trusted, so SSR works out of the box, but forward-auth requests from your reverse proxy will be ignored until its address is added.',
  userHeader: 'User ID Header',
  usernameHeader: 'Username Header',
  emailHeader: 'Email Header',
  rolesHeader: 'Roles Header',
  rolesSeparator: 'Roles Separator',
  rolesSeparatorTip:
    'Character used to split the roles header into individual role names.',
  trustedProxies: 'Trusted Proxies',
  trustedProxiesTip:
    'IPs or CIDR blocks allowed to send authentication headers, in addition to loopback (which is always trusted so SSR works without configuration). Headers from any other source are ignored. The check is performed against the direct TCP peer, not X-Forwarded-For.',
  adminRoles: 'Admin Roles',
  adminRolesTip:
    'Users carrying any of these roles in the roles header are granted full administrator access.',
  roleMapping: 'Role to Permission Mapping',
  roleMappingTip:
    'Permissions granted to users carrying the corresponding role. Multiple matching roles combine.',
  syncPermissions: 'Sync Permissions on Every Request',
  syncPermissionsTip:
    'When enabled, the user’s permissions are recomputed from the roles header on every request. Disable to allow local overrides via the user-management UI.',
  addRow: 'Add',
  remove: 'Remove',
  rolePlaceholder: 'role-name',
  cidrPlaceholder: '10.0.0.0/24',
});

const SettingsUsers = () => {
  const { addToast } = useToasts();
  const intl = useIntl();
  const {
    data,
    error,
    mutate: revalidate,
  } = useSWR<MainSettings>('/api/v1/settings/main');
  const {
    data: headerAuthData,
    error: headerAuthError,
    mutate: revalidateHeaderAuth,
  } = useSWR<HeaderAuthSettings>('/api/v1/settings/main/headerauth');
  const settings = useSettings();

  const schema = yup
    .object()
    .shape({
      localLogin: yup.boolean(),
      mediaServerLogin: yup.boolean(),
    })
    .test({
      name: 'atLeastOneAuth',
      test: function (values) {
        const isValid = (
          ['localLogin', 'mediaServerLogin'] as (keyof typeof values)[]
        ).some((field) => !!values[field]);

        if (isValid) return true;
        return this.createError({
          path: 'localLogin | mediaServerLogin',
          message: intl.formatMessage(messages.atLeastOneAuth),
        });
      },
    });

  if ((!data && !error) || (!headerAuthData && !headerAuthError)) {
    return <LoadingSpinner />;
  }

  const mediaServerFormatValues = {
    mediaServerName:
      settings.currentSettings.mediaServerType === MediaServerType.JELLYFIN
        ? 'Jellyfin'
        : settings.currentSettings.mediaServerType === MediaServerType.EMBY
          ? 'Emby'
          : settings.currentSettings.mediaServerType === MediaServerType.PLEX
            ? 'Plex'
            : undefined,
  };

  return (
    <>
      <PageTitle
        title={[
          intl.formatMessage(messages.users),
          intl.formatMessage(globalMessages.settings),
        ]}
      />
      <div className="mb-6">
        <h3 className="heading">{intl.formatMessage(messages.userSettings)}</h3>
        <p className="description">
          {intl.formatMessage(messages.userSettingsDescription)}
        </p>
      </div>
      <div className="section">
        <Formik
          initialValues={{
            localLogin: data?.localLogin,
            mediaServerLogin: data?.mediaServerLogin,
            newPlexLogin: data?.newPlexLogin,
            movieQuotaLimit: data?.defaultQuotas.movie.quotaLimit ?? 0,
            movieQuotaDays: data?.defaultQuotas.movie.quotaDays ?? 7,
            tvQuotaLimit: data?.defaultQuotas.tv.quotaLimit ?? 0,
            tvQuotaDays: data?.defaultQuotas.tv.quotaDays ?? 7,
            defaultPermissions: data?.defaultPermissions ?? 0,
          }}
          validationSchema={schema}
          enableReinitialize
          onSubmit={async (values) => {
            try {
              await axios.post('/api/v1/settings/main', {
                localLogin: values.localLogin,
                mediaServerLogin: values.mediaServerLogin,
                newPlexLogin: values.newPlexLogin,
                defaultQuotas: {
                  movie: {
                    quotaLimit: values.movieQuotaLimit,
                    quotaDays: values.movieQuotaDays,
                  },
                  tv: {
                    quotaLimit: values.tvQuotaLimit,
                    quotaDays: values.tvQuotaDays,
                  },
                },
                defaultPermissions: values.defaultPermissions,
              });
              mutate('/api/v1/settings/public');

              addToast(intl.formatMessage(messages.toastSettingsSuccess), {
                autoDismiss: true,
                appearance: 'success',
              });
            } catch {
              addToast(intl.formatMessage(messages.toastSettingsFailure), {
                autoDismiss: true,
                appearance: 'error',
              });
            } finally {
              revalidate();
            }
          }}
        >
          {({ isSubmitting, isValid, values, errors, setFieldValue }) => {
            return (
              <Form className="section">
                <div
                  role="group"
                  aria-labelledby="group-label"
                  className="form-group"
                >
                  <div className="form-row">
                    <span id="group-label" className="group-label">
                      {intl.formatMessage(messages.loginMethods)}
                      <span className="label-tip">
                        {intl.formatMessage(messages.loginMethodsTip)}
                      </span>
                      {'localLogin | mediaServerLogin' in errors && (
                        <span className="error">
                          {errors['localLogin | mediaServerLogin'] as string}
                        </span>
                      )}
                    </span>

                    <div className="form-input-area max-w-lg">
                      <LabeledCheckbox
                        id="localLogin"
                        label={intl.formatMessage(messages.localLogin)}
                        description={intl.formatMessage(
                          messages.localLoginTip,
                          mediaServerFormatValues
                        )}
                        onChange={() =>
                          setFieldValue('localLogin', !values.localLogin)
                        }
                      />
                      <LabeledCheckbox
                        id="mediaServerLogin"
                        className="mt-4"
                        label={intl.formatMessage(
                          messages.mediaServerLogin,
                          mediaServerFormatValues
                        )}
                        description={intl.formatMessage(
                          messages.mediaServerLoginTip,
                          mediaServerFormatValues
                        )}
                        onChange={() =>
                          setFieldValue(
                            'mediaServerLogin',
                            !values.mediaServerLogin
                          )
                        }
                      />
                      {!values.mediaServerLogin && values.localLogin && (
                        <div className="mt-4">
                          <Alert
                            title={intl.formatMessage(
                              messages.disabledMediaServerLoginWarning,
                              {
                                applicationTitle:
                                  settings.currentSettings.applicationTitle,
                                ...mediaServerFormatValues,
                              }
                            )}
                            type="warning"
                          />
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                <div className="form-row">
                  <label htmlFor="newPlexLogin" className="checkbox-label">
                    {intl.formatMessage(
                      messages.newPlexLogin,
                      mediaServerFormatValues
                    )}
                    <span className="label-tip">
                      {intl.formatMessage(
                        messages.newPlexLoginTip,
                        mediaServerFormatValues
                      )}
                    </span>
                  </label>
                  <div className="form-input-area">
                    <Field
                      type="checkbox"
                      id="newPlexLogin"
                      name="newPlexLogin"
                      onChange={() => {
                        setFieldValue('newPlexLogin', !values.newPlexLogin);
                      }}
                    />
                  </div>
                </div>
                <div className="form-row">
                  <label htmlFor="applicationTitle" className="text-label">
                    {intl.formatMessage(messages.movieRequestLimitLabel)}
                  </label>
                  <div className="form-input-area">
                    <QuotaSelector
                      onChange={setFieldValue}
                      dayFieldName="movieQuotaDays"
                      limitFieldName="movieQuotaLimit"
                      mediaType="movie"
                      defaultDays={values.movieQuotaDays}
                      defaultLimit={values.movieQuotaLimit}
                    />
                  </div>
                </div>
                <div className="form-row">
                  <label htmlFor="applicationTitle" className="text-label">
                    {intl.formatMessage(messages.tvRequestLimitLabel)}
                  </label>
                  <div className="form-input-area">
                    <QuotaSelector
                      onChange={setFieldValue}
                      dayFieldName="tvQuotaDays"
                      limitFieldName="tvQuotaLimit"
                      mediaType="tv"
                      defaultDays={values.tvQuotaDays}
                      defaultLimit={values.tvQuotaLimit}
                    />
                  </div>
                </div>
                <div
                  role="group"
                  aria-labelledby="group-label"
                  className="form-group"
                >
                  <div className="form-row">
                    <span id="group-label" className="group-label">
                      {intl.formatMessage(messages.defaultPermissions)}
                      <span className="label-tip">
                        {intl.formatMessage(messages.defaultPermissionsTip)}
                      </span>
                    </span>
                    <div className="form-input-area">
                      <div className="max-w-lg">
                        <PermissionEdit
                          currentPermission={values.defaultPermissions}
                          onUpdate={(newPermissions) =>
                            setFieldValue('defaultPermissions', newPermissions)
                          }
                        />
                      </div>
                    </div>
                  </div>
                </div>
                <div className="actions">
                  <div className="flex justify-end">
                    <span className="ml-3 inline-flex rounded-md shadow-sm">
                      <Button
                        buttonType="primary"
                        type="submit"
                        disabled={isSubmitting || !isValid}
                      >
                        <ArrowDownOnSquareIcon />
                        <span>
                          {isSubmitting
                            ? intl.formatMessage(globalMessages.saving)
                            : intl.formatMessage(globalMessages.save)}
                        </span>
                      </Button>
                    </span>
                  </div>
                </div>
              </Form>
            );
          }}
        </Formik>
      </div>
      <div className="mb-6 mt-10">
        <h3 className="heading">{intl.formatMessage(messages.forwardAuth)}</h3>
        <p className="description">
          {intl.formatMessage(messages.forwardAuthDescription)}
        </p>
      </div>
      <div className="section">
        <Formik
          initialValues={{
            enabled: headerAuthData?.enabled ?? false,
            userHeader: headerAuthData?.userHeader ?? 'x-auth-user',
            usernameHeader: headerAuthData?.usernameHeader ?? 'x-auth-username',
            emailHeader: headerAuthData?.emailHeader ?? 'x-auth-email',
            rolesHeader: headerAuthData?.rolesHeader ?? 'x-auth-roles',
            rolesSeparator: headerAuthData?.rolesSeparator ?? ',',
            adminRoles: headerAuthData?.adminRoles ?? [],
            roleMapping: headerAuthData?.roleMapping ?? [],
            trustedProxies: headerAuthData?.trustedProxies ?? [],
            syncPermissions: headerAuthData?.syncPermissions ?? true,
          }}
          enableReinitialize
          onSubmit={async (values) => {
            try {
              await axios.post('/api/v1/settings/main/headerauth', values);
              mutate('/api/v1/settings/public');
              addToast(intl.formatMessage(messages.toastSettingsSuccess), {
                autoDismiss: true,
                appearance: 'success',
              });
            } catch {
              addToast(intl.formatMessage(messages.toastSettingsFailure), {
                autoDismiss: true,
                appearance: 'error',
              });
            } finally {
              revalidateHeaderAuth();
            }
          }}
        >
          {({ isSubmitting, values, setFieldValue }) => (
            <Form className="section">
              <div className="form-row">
                <label htmlFor="haEnabled" className="checkbox-label">
                  {intl.formatMessage(messages.forwardAuthEnabled)}
                  <span className="label-tip">
                    {intl.formatMessage(messages.forwardAuthEnabledTip)}
                  </span>
                </label>
                <div className="form-input-area">
                  <Field
                    type="checkbox"
                    id="haEnabled"
                    name="enabled"
                    onChange={() => setFieldValue('enabled', !values.enabled)}
                  />
                </div>
              </div>

              {values.enabled && values.trustedProxies.length === 0 && (
                <div className="form-row">
                  <div className="form-input-area">
                    <Alert
                      title={intl.formatMessage(
                        messages.trustedProxiesEmptyWarning
                      )}
                      type="warning"
                    />
                  </div>
                </div>
              )}

              <div className="form-row">
                <label htmlFor="userHeader" className="text-label">
                  {intl.formatMessage(messages.userHeader)}
                </label>
                <div className="form-input-area">
                  <div className="form-input-field">
                    <Field id="userHeader" name="userHeader" type="text" />
                  </div>
                </div>
              </div>
              <div className="form-row">
                <label htmlFor="usernameHeader" className="text-label">
                  {intl.formatMessage(messages.usernameHeader)}
                </label>
                <div className="form-input-area">
                  <div className="form-input-field">
                    <Field
                      id="usernameHeader"
                      name="usernameHeader"
                      type="text"
                    />
                  </div>
                </div>
              </div>
              <div className="form-row">
                <label htmlFor="emailHeader" className="text-label">
                  {intl.formatMessage(messages.emailHeader)}
                </label>
                <div className="form-input-area">
                  <div className="form-input-field">
                    <Field id="emailHeader" name="emailHeader" type="text" />
                  </div>
                </div>
              </div>
              <div className="form-row">
                <label htmlFor="rolesHeader" className="text-label">
                  {intl.formatMessage(messages.rolesHeader)}
                </label>
                <div className="form-input-area">
                  <div className="form-input-field">
                    <Field id="rolesHeader" name="rolesHeader" type="text" />
                  </div>
                </div>
              </div>
              <div className="form-row">
                <label htmlFor="rolesSeparator" className="text-label">
                  {intl.formatMessage(messages.rolesSeparator)}
                  <span className="label-tip">
                    {intl.formatMessage(messages.rolesSeparatorTip)}
                  </span>
                </label>
                <div className="form-input-area">
                  <div className="form-input-field">
                    <Field
                      id="rolesSeparator"
                      name="rolesSeparator"
                      type="text"
                    />
                  </div>
                </div>
              </div>

              <div className="form-row">
                <span className="text-label">
                  {intl.formatMessage(messages.trustedProxies)}
                  <span className="label-tip">
                    {intl.formatMessage(messages.trustedProxiesTip)}
                  </span>
                </span>
                <div className="form-input-area">
                  <FieldArray name="trustedProxies">
                    {({ push, remove }) => (
                      <div className="space-y-2">
                        {values.trustedProxies.map((_, idx) => (
                          <div key={idx} className="flex items-center gap-2">
                            <Field
                              name={`trustedProxies.${idx}`}
                              type="text"
                              placeholder={intl.formatMessage(
                                messages.cidrPlaceholder
                              )}
                              className="flex-1"
                            />
                            <Button
                              buttonType="danger"
                              type="button"
                              onClick={() => remove(idx)}
                            >
                              <TrashIcon />
                              <span>{intl.formatMessage(messages.remove)}</span>
                            </Button>
                          </div>
                        ))}
                        <Button
                          buttonType="default"
                          type="button"
                          onClick={() => push('')}
                        >
                          <PlusIcon />
                          <span>{intl.formatMessage(messages.addRow)}</span>
                        </Button>
                      </div>
                    )}
                  </FieldArray>
                </div>
              </div>

              <div className="form-row">
                <span className="text-label">
                  {intl.formatMessage(messages.adminRoles)}
                  <span className="label-tip">
                    {intl.formatMessage(messages.adminRolesTip)}
                  </span>
                </span>
                <div className="form-input-area">
                  <FieldArray name="adminRoles">
                    {({ push, remove }) => (
                      <div className="space-y-2">
                        {values.adminRoles.map((_, idx) => (
                          <div key={idx} className="flex items-center gap-2">
                            <Field
                              name={`adminRoles.${idx}`}
                              type="text"
                              placeholder={intl.formatMessage(
                                messages.rolePlaceholder
                              )}
                              className="flex-1"
                            />
                            <Button
                              buttonType="danger"
                              type="button"
                              onClick={() => remove(idx)}
                            >
                              <TrashIcon />
                              <span>{intl.formatMessage(messages.remove)}</span>
                            </Button>
                          </div>
                        ))}
                        <Button
                          buttonType="default"
                          type="button"
                          onClick={() => push('')}
                        >
                          <PlusIcon />
                          <span>{intl.formatMessage(messages.addRow)}</span>
                        </Button>
                      </div>
                    )}
                  </FieldArray>
                </div>
              </div>

              <div
                role="group"
                aria-labelledby="role-mapping-label"
                className="form-group"
              >
                <div className="form-row">
                  <span id="role-mapping-label" className="group-label">
                    {intl.formatMessage(messages.roleMapping)}
                    <span className="label-tip">
                      {intl.formatMessage(messages.roleMappingTip)}
                    </span>
                  </span>
                  <div className="form-input-area">
                    <FieldArray name="roleMapping">
                      {({ push, remove }) => (
                        <div className="space-y-4">
                          {values.roleMapping.map((entry, idx) => (
                            <div
                              key={idx}
                              className="rounded border border-gray-700 p-4"
                            >
                              <div className="mb-3 flex items-center gap-2">
                                <Field
                                  name={`roleMapping.${idx}.role`}
                                  type="text"
                                  placeholder={intl.formatMessage(
                                    messages.rolePlaceholder
                                  )}
                                  className="flex-1"
                                />
                                <Button
                                  buttonType="danger"
                                  type="button"
                                  onClick={() => remove(idx)}
                                >
                                  <TrashIcon />
                                  <span>
                                    {intl.formatMessage(messages.remove)}
                                  </span>
                                </Button>
                              </div>
                              <div className="max-w-lg">
                                <PermissionEdit
                                  currentPermission={entry.permissions}
                                  onUpdate={(newPermissions) =>
                                    setFieldValue(
                                      `roleMapping.${idx}.permissions`,
                                      newPermissions
                                    )
                                  }
                                />
                              </div>
                            </div>
                          ))}
                          <Button
                            buttonType="default"
                            type="button"
                            onClick={() => push({ role: '', permissions: 0 })}
                          >
                            <PlusIcon />
                            <span>{intl.formatMessage(messages.addRow)}</span>
                          </Button>
                        </div>
                      )}
                    </FieldArray>
                  </div>
                </div>
              </div>

              <div className="form-row">
                <label htmlFor="syncPermissions" className="checkbox-label">
                  {intl.formatMessage(messages.syncPermissions)}
                  <span className="label-tip">
                    {intl.formatMessage(messages.syncPermissionsTip)}
                  </span>
                </label>
                <div className="form-input-area">
                  <Field
                    type="checkbox"
                    id="syncPermissions"
                    name="syncPermissions"
                    onChange={() =>
                      setFieldValue('syncPermissions', !values.syncPermissions)
                    }
                  />
                </div>
              </div>

              <div className="actions">
                <div className="flex justify-end">
                  <span className="ml-3 inline-flex rounded-md shadow-sm">
                    <Button
                      buttonType="primary"
                      type="submit"
                      disabled={isSubmitting}
                    >
                      <ArrowDownOnSquareIcon />
                      <span>
                        {isSubmitting
                          ? intl.formatMessage(globalMessages.saving)
                          : intl.formatMessage(globalMessages.save)}
                      </span>
                    </Button>
                  </span>
                </div>
              </div>
            </Form>
          )}
        </Formik>
      </div>
    </>
  );
};

export default SettingsUsers;
